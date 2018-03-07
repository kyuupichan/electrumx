.. method:: mempool.get_fee_histogram()

  Return a histogram of the fee rates paid by transactions in the
  memory pool, weighted by transaction size.

  **Response**

  The histogram is an array of [*fee*, *vsize*] pairs, where *vsize_n* is
  the cumulative virtual size of mempool transactions with a fee rate
  in the interval [*fee*_(n-1), *fee*_n)], and *fee*_(n-1) > *fee*_n.

  Fee intervals may have variable size.  The choice of appropriate
  intervals is currently not part of the protocol.

  .. versionadded:: 1.2
