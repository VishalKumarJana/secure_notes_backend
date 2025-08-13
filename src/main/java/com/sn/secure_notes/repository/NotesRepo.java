package com.sn.secure_notes.repository;

import com.sn.secure_notes.entity.Notes;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NotesRepo extends JpaRepository<Notes, String> {

    List<Notes> findByOwnerUsername(String ownerUsername);
}
