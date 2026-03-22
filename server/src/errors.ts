export type ApiCliErrorCode =
  | "PROVIDER_NOT_FOUND"
  | "FETCH_ERROR"
  | "TIMEOUT"
  | "INVALID_RESPONSE"
  | "BAD_REQUEST"
  | "METHOD_NOT_ALLOWED"
  | "HTTP_ERROR";

export class ApiCliError extends Error {
  public readonly code: ApiCliErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: ApiCliErrorCode,
    message: string,
    details?: Record<string, unknown>,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ApiCliError";
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
  }
}

export class ApiCliHttpError extends ApiCliError {
  public readonly status: number;
  public readonly responseText: string;
  public readonly responseHeaders: Record<string, string>;

  constructor(input: {
    status: number;
    message: string;
    responseText: string;
    responseHeaders: Record<string, string>;
    details?: Record<string, unknown>;
  }) {
    super("HTTP_ERROR", input.message, input.details);
    this.name = "ApiCliHttpError";
    this.status = input.status;
    this.responseText = input.responseText;
    this.responseHeaders = input.responseHeaders;
  }
}
