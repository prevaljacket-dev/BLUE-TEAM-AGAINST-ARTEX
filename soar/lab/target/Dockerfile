# Cible de LABO volontairement vulnerable. Ne l'exposez JAMAIS sur Internet ni sur votre reseau.
FROM php:8.3-apache
RUN a2enmod rewrite \
    && mkdir -p /var/lib/php/sessions /lab-logs /lab-control \
    && chown www-data:www-data /var/lib/php/sessions \
    && printf 'session.save_path=/var/lib/php/sessions\ndisplay_errors=On\nexpose_php=On\n' > /usr/local/etc/php/conf.d/labo.ini
COPY apache-lab.conf /etc/apache2/sites-available/000-default.conf
COPY www/ /var/www/html/
