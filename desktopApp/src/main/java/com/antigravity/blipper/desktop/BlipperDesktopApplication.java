package com.antigravity.blipper.desktop;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class BlipperDesktopApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(BlipperDesktopApplication.class)
                .headless(false)
                .run(args);
    }
}
