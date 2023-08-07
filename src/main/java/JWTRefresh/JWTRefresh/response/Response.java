package JWTRefresh.JWTRefresh.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Response<T> {
    private String success;
    private String message;
    private T data;
}
