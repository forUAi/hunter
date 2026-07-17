package example;

import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;

class Routes {
  private final StoryStack storyStack = new StoryStack();

  void register(Router router) {
    router.post("/stories/:storyId/action").handler(BodyHandler.create());
    router.post("/stories/:storyId/action").handler(ctx -> updateStory(ctx.pathParam("storyId"), ctx.body().asJsonObject().getString("accountToken")));
  }

  boolean validateAuthentication(String jwt) {
    return true;
  }

  @Transactional
  void updateStory(String storyId, String accountToken) {
    var story = repository.findById(storyId);
    storyStack.transition(story, "COMPLETE");
    auditLog.append(storyId, accountToken);
    logger.info("story updated " + storyId);
  }
}
