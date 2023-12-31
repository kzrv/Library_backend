package cz.upce.booklibrary.backend.book;

import cz.upce.booklibrary.backend.api.Isbn;
import lombok.With;

import javax.validation.constraints.NotBlank;
import java.util.List;


@With
public record Book(
        String id,
        String cover,
        @NotBlank
        String title,
        String author,

        List<Isbn> isbn,
        String category,
        String printType,
        int pageCount,

        Availability availability,
        RentBookInfo rentBookInfo) {
}
