export interface StandardResponse {
  success: boolean;
  message: string;
  data?: any;
  error?: any;
}

export function successResponse(
  message: string,
  data: any = null,
): StandardResponse {
  return {
    success: true,
    message,
    data,
  };
}

export function errorResponse(
  message: string,
  error: any = null,
): StandardResponse {
  return {
    success: false,
    message,
    error,
  };
}
