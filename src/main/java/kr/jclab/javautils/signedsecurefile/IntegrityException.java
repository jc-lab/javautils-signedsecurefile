package kr.jclab.javautils.signedsecurefile;

public class IntegrityException extends Exception {
    public IntegrityException() {
        super();
    }

    public IntegrityException(String message) {
        super(message);
    }

    public IntegrityException(String message, Throwable cause) {
        super(message, cause);
    }

    public IntegrityException(Throwable cause) {
        super(cause);
    }

    protected IntegrityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
