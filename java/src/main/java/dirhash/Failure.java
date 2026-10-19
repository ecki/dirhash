package dirhash;

final class Failure extends RuntimeException {
    final int status;
    final String code;
    String location;

    Failure(int status, String code, String reason) {
        super(reason);
        this.status = status;
        this.code = code;
    }

    static Failure invalid(String code, String reason) {
        return new Failure(1, code, reason);
    }

    static Failure unsupported(String code, String reason) {
        return new Failure(3, code, reason);
    }

    static Failure usage(String reason) {
        return new Failure(2, "USAGE", reason);
    }

    Failure at(String path) {
        location = path;
        return this;
    }
}
