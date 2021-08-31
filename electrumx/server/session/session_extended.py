from copy import deepcopy

import electrumx.lib.util as util

from electrumx.server.session.session import ElectrumX

class AuxPoWElectrumX(ElectrumX):
    async def block_header(self, height, cp_height=0):
        result = await super().block_header(height, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result['header'] = self.truncate_auxpow(result['header'], height)
        return result

    async def block_headers(self, start_height, count, cp_height=0):
        result = await super().block_headers(start_height, count, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result['hex'] = self.truncate_auxpow(result['hex'], start_height)
        return result

    def truncate_auxpow(self, headers_full_hex, start_height):
        height = start_height
        headers_full = util.hex_to_bytes(headers_full_hex)
        cursor = 0
        headers = bytearray()

        while cursor < len(headers_full):
            headers.extend(headers_full[cursor:cursor+self.coin.TRUNCATED_HEADER_SIZE])
            cursor += self.db.dynamic_header_len(height)
            height += 1

        return headers.hex()


class AuxPoWElectrumXElCash(AuxPoWElectrumX):
    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update(
            {
                'blockchain.merged-mining.aux-pow-header': self.get_aux_pow_header,
            }
        )

    async def get_aux_pow_header(self, height):
        header = await super().block_header(height, cp_height=0)
        aux_pow_header = bytes.fromhex(header)[self.coin.TRUNCATED_HEADER_SIZE:].hex()
        return {
            'aux_pow_header': aux_pow_header,
        }

    async def block_header(self, height, cp_height=0):
        result = await super().block_header(height, cp_height)

        if cp_height == 0:
            header = result
        else:
            header = result['header']

        header = self.truncate_auxpow(header, height)
        if cp_height == 0:
            return header
        return {'header': header}

    async def block_headers(self, start_height, count, cp_height=0):
        result = await super().block_headers(start_height, count, cp_height)
        # Covered by a checkpoint; truncate AuxPoW data
        result['hex'] = self.truncate_auxpow(result['hex'], start_height)
        return result

    async def subscribe_headers_result(self):
        results = deepcopy(self.session_mgr.hsub_results)
        header = bytes.fromhex(results['hex'])
        results['hex'] = header[:self.coin.TRUNCATED_HEADER_SIZE].hex()
        return results
