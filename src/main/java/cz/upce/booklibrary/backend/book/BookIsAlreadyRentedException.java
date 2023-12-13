package cz.upce.booklibrary.backend.book;

public class BookIsAlreadyRentedException extends RuntimeException {
    public BookIsAlreadyRentedException(String message) {
        super(message);
    }
}
