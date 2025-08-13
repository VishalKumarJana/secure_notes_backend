package com.sn.secure_notes.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Notes {

    @Id
//    @GeneratedValue(strategy = GenerationType.UUID)
    private String noteId;
    @Lob
    private String content;
    private String ownerUsername;

}
