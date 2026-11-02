package demo.bind;

// 不安全：只校验视频归属，评论按 cid 直删（unsafe）
@RestController
@RequestMapping("/api/videos")
class UnsafeController {

    @Autowired private VideoService videoService;
    @Autowired private CommentService commentService;

    @DeleteMapping("/{id}/comments/{cid}")
    R deleteComment(@PathVariable Long id, @PathVariable Long cid) {
        Video v = videoService.findById(id);
        if (!v.getUserId().equals(SecurityContext.getCurrentUser().getId())) {
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
    void deleteById(Long cid);
}

@Service
class CommentServiceImpl implements CommentService {
    @Autowired private CommentRepository commentRepo;

    public void deleteById(Long cid) {
        commentRepo.deleteById(cid);
    }
}

interface VideoRepository {
    Video findById(Long vid);
}

interface CommentRepository {
    void deleteById(Long cid);
}
