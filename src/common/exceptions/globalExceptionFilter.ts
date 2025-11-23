import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();

        let status: number;
        let message: string | string[];
        if (exception instanceof HttpException) {
            status = exception.getStatus();
            const res = exception.getResponse();
            message =
                typeof res === 'string'
                    ? [res]
                    : Array.isArray((res as any).message)
                        ? (res as any).message
                        : (typeof (res as any).message !== 'undefined'
                            ? [(res as any).message]
                            : ['Unexpected error']);

        } else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            message = ['Internal server error'];
            console.error('Unexpected error:', exception);
        }
        response.status(status).json({
            statusCode: status,
            timestamp: new Date().toISOString(),
            path: request.url,
            method: request.method,
            message,
        });
    }
}
