package demo.bind;

// 安全：父视频归属已校验 + 评论与父视频显式绑定（safe_field）
@RestController
@RequestMapping("/api/videos")
class SafeFieldController {

    @Autowired private VideoService videoService;
    @Autowired private CommentService commentService;

    @DeleteMapping("/{id}/comments/{cid}")
    R deleteComment(@PathVariable Long id, @PathVariable Long cid) {
        Video v = videoService.findById(id);
        if (!v.getUserId().equals(SecurityContext.getCurrentUser().getId())) {
            throw new ForbiddenException();
        }
        Comment c = commentService.findById(cid);
        if (!c.getVideoId().equals(id)) {
            throw new ForbiddenException();
        }
        commentService.deleteById(cid);
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

interface CommentService {
    Comment findById(Long cid);

    void deleteById(Long cid);
}

@Service
class CommentServiceImpl implements CommentService {
    @Autowired private CommentRepository commentRepo;

    public Comment findById(Long cid) {
        return commentRepo.findById(cid);
    }

    public void deleteById(Long cid) {
        commentRepo.deleteById(cid);
    }
}

interface VideoRepository {
    Video findById(Long vid);
}

interface CommentRepository {
    Comment findById(Long cid);

    void deleteById(Long cid);
}
