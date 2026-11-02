package demo.bind;

// 不安全：无归属校验，联合删除的两个参数都由客户端控制（unsafe_repo）
@RestController
@RequestMapping("/api/videos")
class UnsafeRepoController {

    @Autowired private CommentRepository commentRepo;

    @DeleteMapping("/{id}/comments/{cid}")
    R deleteComment(@PathVariable Long id, @PathVariable Long cid) {
        commentRepo.deleteByIdAndVideoId(cid, id);
        return R.ok();
    }
}

interface CommentRepository {
    void deleteByIdAndVideoId(Long cid, Long vid);
}

@Service
class CommentRepositoryImpl implements CommentRepository {
    @Autowired private JdbcTemplate jdbc;

    public void deleteByIdAndVideoId(Long cid, Long vid) {
        jdbc.update("DELETE FROM comment WHERE id = ? AND video_id = ?", cid, vid);
    }
}
