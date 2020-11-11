package kr.ac.korea.sans.tgs.response;

public class TgsErrorResponse extends RuntimeException {
    public TgsErrorResponse(String msg){
        super(msg);
    }
}
