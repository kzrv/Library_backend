package cz.upce.booklibrary.backend.book;

import cz.upce.booklibrary.backend.security.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;

@Service
@RequiredArgsConstructor
public class BookService {

    private final BookRepository bookRepository;
    private final AppUserRepository appUserRepository;


    public List<Book> getAllBooks() {
        return bookRepository.findAll();
    }

    public Book saveBook(Book book) {
        return bookRepository.save(book);
    }

    public Book updateBook(Book updatedBook) {
        return bookRepository.save(updatedBook);
    }

    public void deleteBook(String id) {
        bookRepository.deleteById(id);
    }

    public boolean isBookExisting(String id) {
        return bookRepository.existsById(id);
    }

    public Book rentBook(String id, RentBookInfo rentBookInfo) {
        Book bookToRent = bookRepository.findById(id).orElseThrow(() -> new NoSuchElementException("No Book found with this ID"));

        if (bookToRent.availability() != Availability.AVAILABLE) throw new BookNotAvailableException("Book is not available");
        if ((!bookToRent.rentBookInfo().rentByUsername().isEmpty())) {
            throw new BookIsAlreadyRentedException("Book is already rented to user: " + bookToRent.rentBookInfo().rentByUsername());
        }

        if (!appUserRepository.existsByUsername(rentBookInfo.rentByUsername())) {
            throw new UserNotExistsByUsernameException("Username not found");
        }
        bookToRent = bookToRent.withId(id).withRentBookInfo(rentBookInfo).withAvailability(Availability.NOT_AVAILABLE);
        return bookRepository.save(bookToRent);

    }

    public Book returnBook(String id) {
        Book bookToReturn = bookRepository.findById(id).orElseThrow(() -> new NoSuchElementException("No Book found with this ID"));
        RentBookInfo rentBookInfo = new RentBookInfo("", "");
        bookToReturn = bookToReturn.withId(id).withRentBookInfo(rentBookInfo).withAvailability(Availability.AVAILABLE);
        return bookRepository.save(bookToReturn);
    }

    public List<Book> getRentedBooks(String username) {
        List<Book> books = bookRepository.findAll();
        return books.stream()
                .filter(book -> book.rentBookInfo() != null && book.rentBookInfo().rentByUsername().equals(username)).toList();
    }
}
