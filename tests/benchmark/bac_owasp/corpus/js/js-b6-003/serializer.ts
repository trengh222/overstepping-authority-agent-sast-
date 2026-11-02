// 输出白名单工具：只保留调用方声明的字段
export function pick<T extends Record<string, unknown>, K extends keyof T>(
  source: T,
  keys: readonly K[]
): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const key of keys) {
    if (key in source) {
      out[key] = source[key];
    }
  }
  return out;
}
