package org.zerock.club.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.zerock.club.entity.Note;

import java.util.List;
import java.util.Optional;

public interface NoteRepository extends JpaRepository<Note,Long> {

    @EntityGraph(attributePaths = "writer", type = EntityGraph.EntityGraphType.LOAD)
    @Query("select n from Note n where n.num = :num") // 특정 Note를 조회
    Optional<Note> getWithWriter(Long num); // 조회 결과가 0개 또는 1개 이기에 Optional 사용

    @EntityGraph(attributePaths = {"writer"}, type = EntityGraph.EntityGraphType.LOAD)
    @Query("select n from Note n where n.writer.email = :email") // 해당 사용자의 Note들을 조회
    List<Note> getList(String email);
}
