package cz.upce.booklibrary.backend.security;

public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);

    }
}
