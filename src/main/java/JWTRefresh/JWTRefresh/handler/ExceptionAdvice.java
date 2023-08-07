package JWTRefresh.JWTRefresh.handler;

import JWTRefresh.JWTRefresh.response.Response;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionAdvice {
    @ExceptionHandler(IllegalArgumentException.class)
    public Response<?> illegalArgumentExceptionAdvice(IllegalArgumentException e) {
        return new Response<>("fail", e.getMessage().toString(), null);
    }
}
