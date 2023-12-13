package cz.upce.booklibrary.backend.api;

import cz.upce.booklibrary.backend.book.Availability;
import lombok.With;

@With
public record ApiBook(
        String id,
        VolumeInfo volumeInfo,
        Availability availability

) {

}
