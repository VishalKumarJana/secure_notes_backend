package com.sn.secure_notes.serviceimpl;

import com.sn.secure_notes.entity.Notes;
import com.sn.secure_notes.repository.NotesRepo;
import com.sn.secure_notes.service.AuditLogService;
import com.sn.secure_notes.service.NotesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;


@Service
public class NotesServiceImpl implements NotesService {

    @Autowired
    private NotesRepo notesRepo;

    @Autowired
    private AuditLogService auditLogService;

    @Override
    public Notes createNotesForUser(String username, String content) {
        Notes notes = new Notes();
        notes.setNoteId(UUID.randomUUID().toString());
        notes.setContent(content);
        notes.setOwnerUsername(username);
        auditLogService.logCreation(username, notes);
        return notesRepo.save(notes);
    }

    @Override
    public List<Notes> getNotesForUser(String username) {
        return notesRepo.findByOwnerUsername(username);
    }

    @Override
    public Notes updateNotesForUser(String noteId, String username, String content) {
        Notes notes = notesRepo.findById(noteId).orElseThrow(() -> new RuntimeException("Note Not Found"));
        notes.setContent(content);
        Notes save = notesRepo.save(notes);
        auditLogService.logUpdate(username, notes);
        return save;
    }

    @Override
    public void deleteNotesForUser(String noteId, String username) {
        Notes notes = notesRepo.findById(noteId).orElseThrow(() -> new RuntimeException("Note Not Found"));
        auditLogService.logDelete(username, noteId);
        notesRepo.delete(notes);
    }


}
