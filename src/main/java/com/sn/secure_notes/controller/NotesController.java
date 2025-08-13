package com.sn.secure_notes.controller;

import com.sn.secure_notes.entity.Notes;
import com.sn.secure_notes.service.NotesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/secure-note/api/notes")
public class NotesController {

    @Autowired
    private NotesService notesService;

    @PostMapping
    public Notes createNote(@RequestBody String content,
                            @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        return notesService.createNotesForUser(username, content);
    }

    @GetMapping
    public List<Notes> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        return notesService.getNotesForUser(username);
    }

    @PutMapping("/{noteId}")
    public Notes updateNote(@PathVariable String noteId, @AuthenticationPrincipal UserDetails userDetails, @RequestBody String content) {
        String username = userDetails.getUsername();
        return notesService.updateNotesForUser(noteId, username, content);
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable String noteId, @AuthenticationPrincipal UserDetails userDetails) {
        notesService.deleteNotesForUser(noteId, userDetails.getUsername());
    }

}
