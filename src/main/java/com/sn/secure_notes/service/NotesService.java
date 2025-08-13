package com.sn.secure_notes.service;

import com.sn.secure_notes.entity.Notes;

import java.util.List;

public interface NotesService {

    Notes createNotesForUser(String username, String content);

    List<Notes> getNotesForUser(String username);

    Notes updateNotesForUser(String noteId, String username, String content);

    void deleteNotesForUser(String noteId, String username);

}
