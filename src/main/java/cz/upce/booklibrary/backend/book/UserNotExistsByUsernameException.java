package cz.upce.booklibrary.backend.book;

public class UserNotExistsByUsernameException extends RuntimeException {

    public UserNotExistsByUsernameException(String message) {
        super(message);

    }
}
