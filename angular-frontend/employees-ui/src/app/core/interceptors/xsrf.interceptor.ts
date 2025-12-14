import { HttpInterceptorFn } from '@angular/common/http';
import { environment } from '@env/environment';
import { getCookie } from '@shared/utils/cookie.util';

const XSRF_HEADER_NAME = 'X-XSRF-TOKEN';
const XSRF_COOKIE_NAME = 'XSRF-TOKEN';

const MUTATING_HTTP_METHODS = new Set([
    'POST',
    'PUT',
    'PATCH',
    'DELETE'
]);

// Normalize apiBaseUrl once (remove trailing slash if present)
const API_BASE_URL = environment.apiBaseUrl.replace(/\/+$/, '');

const isMutatingRequest = (method: string): boolean =>
    MUTATING_HTTP_METHODS.has(method);

// Only send XSRF header to *our* backend, defined by apiBaseUrl
const isApiRequest = (url: string): boolean =>
    url.startsWith(API_BASE_URL + '/');

/**
 * XSRF interceptor for API calls using absolute (potentially cross-origin) URLs.
 *
 * Angular's built-in XSRF protection only attaches the `X-XSRF-TOKEN` header
 * automatically for mutating requests (POST/PUT/PATCH/DELETE) to
 * same-origin or relative URLs.
 *
 * In this application, the backend is called via an absolute `apiBaseUrl`
 * (which is cross-origin in development, e.g. http://localhost:8090 while
 * the SPA runs on http://localhost:4200),
 * so Angular does NOT add the XSRF header automatically in this scenario.
 *
 * This interceptor explicitly reads the `XSRF-TOKEN` cookie and injects it
 * as the `X-XSRF-TOKEN` header for mutating requests to our backend API.
 */
export const xsrfInterceptor: HttpInterceptorFn = (req, next) => {
    if (!isMutatingRequest(req.method)) {
        return next(req);
    }

    if (!isApiRequest(req.url)) {
        return next(req);
    }

    // do not override if already set for some reason
    if (req.headers.has(XSRF_HEADER_NAME)) {
        return next(req);
    }

    const token = getCookie(XSRF_COOKIE_NAME);
    if (!token) {
        return next(req);
    }

    return next(
        req.clone({
            setHeaders: {
                [XSRF_HEADER_NAME]: token
            }
        })
    );
};
