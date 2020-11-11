package kr.ac.korea.sans.tgs.response;

import lombok.*;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class TgsAppResponse<T> {
    @NonNull
    private T body;
//    private Map<String, Object> body;
    private String signature;
}
