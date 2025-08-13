package com.sn.secure_notes.controller;

import com.sn.secure_notes.entity.AuditLog;
import com.sn.secure_notes.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("secure-note/api/audit")
public class AuditLogController {

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping
    public List<AuditLog> getAllAuditLogs() {
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/notes/{noteId}")
    public List<AuditLog> getNotesAuditLogs(@PathVariable String noteId) {
        return auditLogService.getAuditLogsForNotesId(noteId);
    }

}
