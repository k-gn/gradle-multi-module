package com.module.web;

import org.springframework.stereotype.Component;

import com.module.server.Server;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class Web {

	private final Server server;
}
