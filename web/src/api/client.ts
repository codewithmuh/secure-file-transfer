/**
 * The typed API client (FR-31). Paths, parameters, request bodies and response bodies all come from `schema.ts`,
 * which `npm run gen:api` generates from `docs/api/openapi.yaml`; CI fails when the two differ.
 *
 * Every request goes through the one axios instance in `@/lib/api`, so its interceptors still choose the credential
 * (the member CSRF token, or the link session's ID and token) and handle a `401` (#73). Errors are `AxiosError`s, as
 * before.
 */
import type { AxiosRequestConfig, AxiosResponse } from 'axios';
import { apiClient } from '@/lib/api';
import type { components, paths } from './schema';

/** A named schema from the contract, for example `Schema<'Transfer'>`. */
export type Schema<Name extends keyof components['schemas']> = components['schemas'][Name];

/**
 * The paths the web app may call. The `/operator` paths belong to the operator API, which only operators reach
 * through a port-forward (authn-authz 8.2), so the client leaves them out.
 */
export type ApiPaths = Omit<paths, `/operator/${string}`>;
export type ApiPath = keyof ApiPaths;
export type HttpMethod = 'get' | 'put' | 'post' | 'patch' | 'delete';

/** The operation at a path and method, or `never` if the contract has none. */
export type Operation<P extends ApiPath, M extends HttpMethod> = ApiPaths[P] extends { [K in M]: infer O } ? O : never;

/** The paths that have an operation for a method. */
export type PathsWith<M extends HttpMethod> = {
  [P in ApiPath]: [Operation<P, M>] extends [never] ? never : P;
}[ApiPath];

type ParametersOf<O> = O extends { parameters: infer Params } ? Params : never;
type PathParams<O> = ParametersOf<O> extends { path: infer X } ? X : never;
type QueryParams<O> = ParametersOf<O> extends { query?: infer X } ? Exclude<X, undefined> : never;
/** The request interceptor sets `X-Link-Session` from the link session, so callers never pass it. */
type HeaderParams<O> =
  ParametersOf<O> extends { header?: infer X } ? Omit<Exclude<X, undefined>, 'X-Link-Session'> : never;
type JsonBody<O> = O extends { requestBody?: { content: { 'application/json': infer B } } } ? B : never;

type RequiredKeys<T> = { [K in keyof T]-?: Record<never, never> extends Pick<T, K> ? never : K }[keyof T];

/** An option named `K`: absent when the operation has none, required when the contract requires it. */
type Field<K extends string, V, Required extends boolean> = [V] extends [never]
  ? { [_ in K]?: never }
  : Required extends true
    ? { [_ in K]: V }
    : { [_ in K]?: V };

export type RequestOptions<O> = Field<'path', PathParams<O>, true> &
  Field<'query', QueryParams<O>, ParametersOf<O> extends { query: object } ? true : false> &
  Field<'headers', HeaderParams<O>, [RequiredKeys<HeaderParams<O>>] extends [never] ? false : true> &
  Field<'body', JsonBody<O>, O extends { requestBody: object } ? true : false> &
  Pick<AxiosRequestConfig, 'signal' | 'timeout' | 'onUploadProgress' | 'onDownloadProgress' | 'skipAuthRedirect'>;

/** The options argument, which may be left out when nothing in it is required. */
type OptionsArg<O> =
  [RequiredKeys<RequestOptions<O>>] extends [never] ? [options?: RequestOptions<O>] : [options: RequestOptions<O>];

type SuccessStatus = 200 | 201 | 202 | 203 | 204 | 205 | 206;
type ResponsesOf<O> = O extends { responses: infer R } ? R : never;
type ContentOf<R> = R extends { content: infer C }
  ? C extends { 'application/json': infer B }
    ? B
    : C[keyof C]
  : undefined;

/** The body of any success response of an operation; `undefined` for a response without one, such as `204`. */
export type ResponseBody<O> = {
  [S in keyof ResponsesOf<O> & SuccessStatus]: ContentOf<ResponsesOf<O>[S]>;
}[keyof ResponsesOf<O> & SuccessStatus];

interface LooseOptions extends Pick<AxiosRequestConfig, 'signal' | 'timeout' | 'skipAuthRedirect'> {
  path?: Record<string, unknown>;
  query?: object;
  headers?: object;
  body?: unknown;
}

/**
 * Fills the `{name}` segments of a contract path. Each value is percent-encoded, and a missing, empty or dot-segment
 * value is refused, so an ID taken from the address bar can't turn `/transfers/{transfer_id}/files` into another
 * route (the browser resolves `..` before sending).
 */
export function fillPath(template: string, values: Record<string, unknown> | undefined): string {
  return template.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const value = values?.[name];
    const text = value === undefined || value === null ? '' : String(value);
    if (text === '' || text === '.' || text === '..') {
      throw new Error(`Path parameter "${name}" of ${template} is missing or not a single path segment`);
    }
    return encodeURIComponent(text);
  });
}

function send(method: HttpMethod, template: string, options: LooseOptions | undefined): Promise<AxiosResponse> {
  const { path, query, headers, body, ...config } = options ?? {};
  return apiClient.request({
    ...config,
    method,
    url: fillPath(template, path),
    params: query,
    // The contract's array parameters are `style: form, explode: true`: `state=sent&state=held`, not `state[]=`.
    paramsSerializer: { indexes: null },
    headers: headers as AxiosRequestConfig['headers'],
    data: body,
  });
}

type Call<M extends HttpMethod> = <P extends PathsWith<M>>(
  path: P,
  ...options: OptionsArg<Operation<P, M>>
) => Promise<AxiosResponse<ResponseBody<Operation<P, M>>>>;

function method<M extends HttpMethod>(name: M): Call<M> {
  return ((path: string, options?: LooseOptions) => send(name, path, options)) as Call<M>;
}

/**
 * Calls the API by its contract path, for example
 * `api.get('/transfers/{transfer_id}', { path: { transfer_id } })`, which resolves to a response whose `data` is a
 * `Schema<'Transfer'>`.
 */
export const api = {
  get: method('get'),
  put: method('put'),
  post: method('post'),
  patch: method('patch'),
  delete: method('delete'),
};
