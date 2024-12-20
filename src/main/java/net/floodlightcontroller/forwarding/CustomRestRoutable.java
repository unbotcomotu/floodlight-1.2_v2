package net.floodlightcontroller.forwarding;

import net.floodlightcontroller.restserver.RestletRoutable;
import org.restlet.Context;
import org.restlet.routing.Router;

public class CustomRestRoutable implements RestletRoutable {
    @Override
    public Router getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/deleteRulesByMac", DeleteFlowRulesResource.class);
        return router;
    }

    @Override
    public String basePath() {
        return "/custom"; // La base de tu endpoint
    }
}
