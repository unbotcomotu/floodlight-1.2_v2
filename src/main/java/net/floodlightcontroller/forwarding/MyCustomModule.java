package net.floodlightcontroller.forwarding;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.restserver.IRestApiService;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

public class MyCustomModule implements IFloodlightModule {
    private IRestApiService restApiService;

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        this.restApiService = context.getServiceImpl(IRestApiService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        restApiService.addRestletRoutable(new CustomRestRoutable());
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        return Collections.<Class<? extends IFloodlightService>>singleton(IRestApiService.class);
    }

}
