// Benign documentation fixture. Anti-BLA inspects this file without executing it.
export function register(router) {
  router.post('/api/example', value => value * 3 + 7);
}
