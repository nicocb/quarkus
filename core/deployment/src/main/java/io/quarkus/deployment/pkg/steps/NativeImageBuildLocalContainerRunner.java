package io.quarkus.deployment.pkg.steps;

import static io.quarkus.deployment.pkg.steps.LinuxIDUtil.getLinuxID;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.SystemUtils;

import io.quarkus.deployment.pkg.NativeConfig;
import io.quarkus.deployment.util.ContainerRuntimeUtil;
import io.quarkus.deployment.util.FileUtil;

public class NativeImageBuildLocalContainerRunner extends NativeImageBuildContainerRunner {

    public NativeImageBuildLocalContainerRunner(NativeConfig nativeConfig, Path outputDir) {
        super(nativeConfig, outputDir);
        if (SystemUtils.IS_OS_LINUX) {
            ArrayList<String> containerRuntimeArgs = new ArrayList<>(Arrays.asList(baseContainerRuntimeArgs));
            String uid = getLinuxID("-ur");
            String gid = getLinuxID("-gr");
            if (uid != null && gid != null && !uid.isEmpty() && !gid.isEmpty()) {
                Collections.addAll(containerRuntimeArgs, "--user", uid + ":" + gid);
                if (containerRuntime == ContainerRuntimeUtil.ContainerRuntime.PODMAN) {
                    // Needed to avoid AccessDeniedExceptions
                    containerRuntimeArgs.add("--userns=keep-id");
                }
            }
            baseContainerRuntimeArgs = containerRuntimeArgs.toArray(baseContainerRuntimeArgs);
        }
    }

    @Override
    protected List<String> getContainerRuntimeBuildArgs() {
        List<String> containerRuntimeArgs = super.getContainerRuntimeBuildArgs();
        String volumeOutputPath = outputPath;
        if (SystemUtils.IS_OS_WINDOWS) {
            volumeOutputPath = FileUtil.translateToVolumePath(volumeOutputPath);
        }

        Collections.addAll(containerRuntimeArgs, "-v",
                volumeOutputPath + ":" + NativeImageBuildStep.CONTAINER_BUILD_VOLUME_PATH + ":z");
        return containerRuntimeArgs;
    }
}
