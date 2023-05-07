const NAMESPACE = "dilithium_";

function poly_reduce(a) {
  // function implementation
}

function poly_caddq(a) {
  // function implementation
}

// 重命名函数名
const poly_reduce_renamed = NAMESPACE + "poly_reduce";
const poly_caddq_renamed = NAMESPACE + "poly_caddq";

// 将重命名后的函数名绑定到原始函数
window[poly_reduce_renamed] = poly_reduce;
window[poly_caddq_renamed] = poly_caddq;
