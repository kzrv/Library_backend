package cz.upce.booklibrary.backend.api;

import lombok.With;


@With
public record Isbn(String type,
                   String identifier) {
}


