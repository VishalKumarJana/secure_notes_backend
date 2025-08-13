package com.sn.secure_notes.repository;

import com.sn.secure_notes.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepo extends JpaRepository<AuditLog, String> {
    List<AuditLog> findByNoteId(String noteId);
}
