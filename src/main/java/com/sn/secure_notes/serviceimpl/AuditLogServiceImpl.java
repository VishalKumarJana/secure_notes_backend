package com.sn.secure_notes.serviceimpl;

import com.sn.secure_notes.entity.AuditLog;
import com.sn.secure_notes.entity.Notes;
import com.sn.secure_notes.repository.AuditLogRepo;
import com.sn.secure_notes.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    @Autowired
    private AuditLogRepo auditLogRepo;

    @Override
    public void logCreation(String username, Notes notes){
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("CREATED");
        auditLog.setUsername(username);
        auditLog.setNoteId(notes.getNoteId());
        auditLog.setNoteContent(notes.getContent());
        auditLog.setTimestamp(LocalDateTime.now());
        auditLogRepo.save(auditLog);
    }

    @Override
    public void logUpdate(String username, Notes notes){
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("UPDATED");
        auditLog.setUsername(username);
        auditLog.setNoteId(notes.getNoteId());
        auditLog.setNoteContent(notes.getContent());
        auditLog.setTimestamp(LocalDateTime.now());
        auditLogRepo.save(auditLog);
    }

    @Override
    public void logDelete(String username, String noteId){
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("DELETED");
        auditLog.setUsername(username);
        auditLog.setNoteId(noteId);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLogRepo.save(auditLog);
    }

    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepo.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsForNotesId(String noteId) {
        return auditLogRepo.findByNoteId(noteId);
    }
}
