
# source https://github.com/docker-library/php/blob/0274f58b8dcf68a23d8fd77101d2d4c74d38fc65/7.4/alpine3.12/fpm/Dockerfile

FROM alpine:3.12

# dependencies required for running "phpize"
# these get automatically installed and removed by "docker-php-ext-*" (unless they're already installed)
ENV PHPIZE_DEPS \
		autoconf \
		dpkg-dev dpkg \
		file \
		g++ \
		gcc \
		libc-dev \
		make \
		pkgconf \
		re2c

ENV PHP_INI_DIR /usr/local/etc/php

ENV PHP_EXTRA_CONFIGURE_ARGS --enable-fpm --with-fpm-user=nginx --with-fpm-group=www-data --disable-cgi

# Apply stack smash protection to functions using local buffers and alloca()
# Make PHP's main executable position-independent (improves ASLR security mechanism, and has no performance impact on x86_64)
# Enable optimization (-O2)
# Enable linker optimization (this sorts the hash buckets to improve cache locality, and is non-default)
# https://github.com/docker-library/php/issues/272
# -D_LARGEFILE_SOURCE and -D_FILE_OFFSET_BITS=64 (https://www.php.net/manual/en/intro.filesystem.php)
ENV PHP_CFLAGS="-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"
ENV PHP_CPPFLAGS="$PHP_CFLAGS"
ENV PHP_LDFLAGS="-Wl,-O1 -pie"

ENV GPG_KEYS 42670A7FE4D0441C8E4632349E4FDC074A4EF02D 5A52880781F755608BF815FC910DEB46F53EA312

ENV PHP_VERSION 7.4.13
ENV PHP_URL="https://www.php.net/distributions/php-7.4.13.tar.xz" PHP_ASC_URL="https://www.php.net/distributions/php-7.4.13.tar.xz.asc"
ENV PHP_SHA256="aead303e3abac23106529560547baebbedba0bb2943b91d5aa08fff1f41680f4"

COPY ./docker_files/docker-php-source /usr/local/bin/
COPY ./docker_files/docker-php-ext-* ./docker_files/docker-php-entrypoint /usr/local/bin/

# ensure www-data user exists
# 82 is the standard uid/gid for "www-data" in Alpine
# https://git.alpinelinux.org/aports/tree/main/apache2/apache2.pre-install?h=3.9-stable
# https://git.alpinelinux.org/aports/tree/main/lighttpd/lighttpd.pre-install?h=3.9-stable
# https://git.alpinelinux.org/aports/tree/main/nginx/nginx.pre-install?h=3.9-stable
RUN set -eux; \
	addgroup -g 82 -S www-data; \
	adduser -u 82 -D -S -G www-data nginx; \
	# persistent / runtime deps
	apk update && apk add --no-cache \
		ca-certificates \
		curl \
		tar \
		xz \
		# https://github.com/docker-library/php/issues/494
		openssl \
		runit \
		tzdata \
		ssmtp \
		nginx \
		# BusyBox sed is not sufficient for some of our sed expressions
		sed \
		# Ghostscript is required for rendering PDF previews
		ghostscript \
		# Alpine package for "imagemagick" contains ~120 .so docker_files, see: https://github.com/docker-library/wordpress/pull/497
		imagemagick; \
	mkdir -p "$PHP_INI_DIR/conf.d"; \
# allow running as an arbitrary user (https://github.com/docker-library/php/issues/743)
	[ ! -d /www ]; \
	mkdir -p /www; \
	chown nginx:www-data /www; \
	chmod 777 /www; \
	\
	apk add --no-cache --virtual .fetch-deps gnupg; \
	\
	mkdir -p /usr/src; \
	cd /usr/src; \
	\
	curl -fsSL -o php.tar.xz "$PHP_URL"; \
	\
	if [ -n "$PHP_SHA256" ]; then \
		echo "$PHP_SHA256 *php.tar.xz" | sha256sum -c -; \
	fi; \
	\
	if [ -n "$PHP_ASC_URL" ]; then \
		curl -fsSL -o php.tar.xz.asc "$PHP_ASC_URL"; \
		export GNUPGHOME="$(mktemp -d)"; \
		for key in $GPG_KEYS; do \
			gpg --batch --keyserver ha.pool.sks-keyservers.net --recv-keys "$key"; \
		done; \
		gpg --batch --verify php.tar.xz.asc php.tar.xz; \
		gpgconf --kill all; \
		rm -rf "$GNUPGHOME"; \
	fi; \
	\
	apk del --no-network .fetch-deps; \
	apk add --no-cache --virtual .build-deps \
		$PHPIZE_DEPS \
		argon2-dev \
		coreutils \
		curl-dev \
		libedit-dev \
		libsodium-dev \
		libxml2-dev \
		linux-headers \
		oniguruma-dev \
		openssl-dev \
		sqlite-dev \
	; \
	\
	export CFLAGS="$PHP_CFLAGS" \
		CPPFLAGS="$PHP_CPPFLAGS" \
		LDFLAGS="$PHP_LDFLAGS" \
	; \
	docker-php-source extract; \
	cd /usr/src/php; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
	./configure \
		--build="$gnuArch" \
		--with-config-file-path="$PHP_INI_DIR" \
		--with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
		\
# make sure invalid --configure-flags are fatal errors instead of just warnings
		--enable-option-checking=fatal \
		\
# https://github.com/docker-library/php/issues/439
		--with-mhash \
		\
# https://github.com/docker-library/php/issues/822
		--with-pic \
		\
# --enable-ftp is included here because ftp_ssl_connect() needs ftp to be compiled statically (see https://github.com/docker-library/php/issues/236)
		# --enable-ftp \
# --enable-mbstring is included here because otherwise there's no way to get pecl to use it properly (see https://github.com/docker-library/php/issues/195)
		--enable-mbstring \
# --enable-mysqlnd is included here because it's harder to compile after the fact than extensions are (since it's a plugin for several extensions, not an extension in itself)
		--enable-mysqlnd \
# https://wiki.php.net/rfc/argon2_password_hash (7.2+)
		--with-password-argon2 \
# https://wiki.php.net/rfc/libsodium
		--with-sodium=shared \
# always build against system sqlite3 (https://github.com/php/php-src/commit/6083a387a81dbbd66d6316a3a12a63f06d5f7109)
		# --with-pdo-sqlite=/usr \
		# --with-sqlite3=/usr \
		\
		--with-curl \
		--without-sqlite3 \
		--with-libedit \
		--with-openssl \
		--with-zlib \
		\
# in PHP 7.4+, the pecl/pear installers are officially deprecated (requiring an explicit "--with-pear")
		--with-pear \
		\
# bundled pcre does not support JIT on s390x
# https://manpages.debian.org/stretch/libpcre3-dev/pcrejit.3.en.html#AVAILABILITY_OF_JIT_SUPPORT
		$(test "$gnuArch" = 's390x-linux-musl' && echo '--without-pcre-jit') \
		\
		${PHP_EXTRA_CONFIGURE_ARGS:-} \
	; \
	make -j "$(nproc)"; \
	find -type f -name '*.a' -delete; \
	make install; \
	find /usr/local/bin /usr/local/sbin -type f -perm +0111 -exec strip --strip-all '{}' + || true; \
	make clean; \
	\
# https://github.com/docker-library/php/issues/692 (copy default example "php.ini" files somewhere easily discoverable)
	cp -v php.ini-* "$PHP_INI_DIR/"; \
	\
	cd /; \
	docker-php-source delete; \
	\
	runDeps="$( \
		scanelf --needed --nobanner --format '%n#p' --recursive /usr/local \
			| tr ',' '\n' \
			| sort -u \
			| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
	)"; \
	apk add --no-cache $runDeps; \
	\
	apk del --no-network .build-deps; \
	\
# update pecl channel definitions https://github.com/docker-library/php/issues/443
	pecl update-channels; \
	rm -rf /tmp/pear ~/.pearrc; \
	\
# smoke test
	php --version; \
	# sodium was built as a shared module (so that it can be replaced later if so desired), so let's enable it too (https://github.com/docker-library/php/issues/598)
	docker-php-ext-enable sodium; \
	docker-php-ext-enable opcache; \
# WORKDIR /
	cd /usr/local/etc; \
	# if [ -d php-fpm.d ]; then \
	# 	# for some reason, upstream's php-fpm.conf.default has "include=NONE/etc/php-fpm.d/*.conf"
	# 	sed 's!=NONE/!=!g' php-fpm.conf.default | tee php-fpm.conf > /dev/null; \
	# 	cp php-fpm.d/www.conf.default php-fpm.d/www.conf; \
	# else \
	# 	# PHP 5.x doesn't use "include=" by default, so we'll create our own simple config that mimics PHP 7+ for consistency
	# 	mkdir php-fpm.d; \
	# 	cp php-fpm.conf.default php-fpm.d/www.conf; \
	# 	{ \
	# 		echo '[global]'; \
	# 		echo 'include=etc/php-fpm.d/*.conf'; \
	# 	} | tee php-fpm.conf; \
	# fi; \
	{ \
		echo '[global]'; \
		echo 'error_log = /proc/self/fd/2'; \
		echo; echo '; https://github.com/docker-library/php/pull/725#issuecomment-443540114'; echo 'log_limit = 8192'; \
		echo; \
		echo '[www]'; \
		echo '; if we send this to /proc/self/fd/1, it never appears'; \
		echo 'access.log = /proc/self/fd/2'; \
		echo; \
		echo 'clear_env = no'; \
		echo; \
		echo '; Ensure worker stdout and stderr are sent to the main error log.'; \
		echo 'catch_workers_output = yes'; \
		echo 'decorate_workers_output = no'; \
	} | tee php-fpm.d/docker.conf; \
	# { \
	# 	echo '[global]'; \
	# 	echo 'daemonize = no'; \
	# }
	# RUN apk add --no-cache \
	#       #   bash \
	# 		  supervisor \
	# source https://github.com/docker-library/wordpress/blob/5b53a06ca346a2396f2e0373959314c5c9c73e04/php7.4/fpm-alpine/Dockerfile
	\
	apk add --no-cache --virtual .build-deps \
		$PHPIZE_DEPS \
		freetype-dev \
		imagemagick-dev \
		libjpeg-turbo-dev \
		libpng-dev \
		libzip-dev \
		libxslt-dev \
      libgcrypt-dev \
		tidyhtml-dev \
		zlib-dev \
		icu-dev \
		# g++ \
	; \
	\
	docker-php-ext-configure intl; \
	# docker-php-ext-configure gd --with-freetype --with-jpeg; \
	docker-php-ext-install -j "$(nproc)" \
		bcmath \
		exif \
		# gd \
		mysqli \
		pdo \
		pdo_mysql \
		zip \
		xsl \
		xmlrpc \
		tidy \
		intl \
		soap \
	; \
	# docker-php-ext-install imagick; \
	pecl install -o -f redis; \
	 rm -rf /tmp/pear; \
    docker-php-ext-enable redis; \
    pecl install imagick-3.4.4; \
	docker-php-ext-enable imagick; \
	\
	runDeps="$( \
		scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
			| tr ',' '\n' \
			| sort -u \
			| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
	)"; \
	apk add --virtual .wordpress-phpexts-rundeps $runDeps; \
	docker-php-ext-install calendar; \
	docker-php-ext-configure calendar; \
	apk del .build-deps


# set recommended PHP.ini settings
# see https://secure.php.net/manual/en/opcache.installation.php
# https://wordpress.org/support/article/editing-wp-config-php/#configure-error-logging

# Clean repository
RUN rm -rf /var/cache/apk/*; \
	mkdir /tmp/nginx/; \
	mkdir /tmp/zlmcache/; \
	chown nginx:www-data /tmp/zlmcache; \
	rm -rf /usr/local/etc/php-fpm.d; \
	rm -rf /usr/local/etc/php-fpm.conf.default

#set timezone
RUN cp /usr/share/zoneinfo/Europe/Rome /etc/localtime && \
	echo "Europe/Rome" >  /etc/timezone && \
	date

COPY docker_files/nginx.conf /etc/nginx/
COPY docker_files/error-logging.ini /usr/local/etc/php/conf.d/
COPY docker_files/opcache-recommended.ini /usr/local/etc/php/conf.d/
COPY docker_files/php-fpm.conf /usr/local/etc/php-fpm.conf
COPY docker_files/rocketstack.conf /etc/nginx/
COPY docker_files/seo_rewrites.conf /etc/nginx/
COPY docker_files/cloudflare.key /etc/ssl/certs/cloudflare.key
COPY docker_files/cloudflare.pem /etc/ssl/certs/cloudflare.pem

EXPOSE 80
EXPOSE 443

WORKDIR /

COPY docker_files/runit_services /etc/service
COPY docker_files/boot.sh /sbin/boot.sh
RUN chmod +x /sbin/boot.sh; \
	 chmod +x -R /etc/service/*
CMD [ "/sbin/boot.sh" ]
