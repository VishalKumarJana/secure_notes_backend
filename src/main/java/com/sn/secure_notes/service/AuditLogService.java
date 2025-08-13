package com.sn.secure_notes.service;

import com.sn.secure_notes.entity.AuditLog;
import com.sn.secure_notes.entity.Notes;

import java.util.List;

public interface AuditLogService {
    void logCreation (String username, Notes notes);

    void logUpdate(String username, Notes notes);

    void logDelete(String username, String noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogsForNotesId(String noteId);
}
