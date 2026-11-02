package demo.bind;

// 安全：父视频归属已校验 + 仓储层联合条件按「评论 id AND 父视频 id」删除（safe_repo）
@RestController
@RequestMapping("/api/videos")
class SafeRepoController {

    @Autowired private VideoService videoService;
    @Autowired private CommentRepository commentRepo;

    @DeleteMapping("/{id}/comments/{cid}")
    R deleteComment(@PathVariable Long id, @PathVariable Long cid) {
        Video v = videoService.findById(id);
        if (!v.getUserId().equals(SecurityContext.getCurrentUser().getId())) {
            throw new ForbiddenException();
        }
        commentRepo.deleteByIdAndVideoId(cid, id);
        return R.ok();
    }
}

interface VideoService {
    Video findById(Long vid);
}

@Service
class VideoServiceImpl implements VideoService {
    @Autowired private VideoRepository videoRepo;

    public Video findById(Long vid) {
        return videoRepo.findById(vid);
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

interface VideoRepository {
    Video findById(Long vid);
}
