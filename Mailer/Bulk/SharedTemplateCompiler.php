<?php

declare(strict_types=1);

namespace MauticPlugin\AmazonSesBundle\Mailer\Bulk;

use Mautic\EmailBundle\Mailer\Message\MauticMessage;

/** Compile Mautic's already-resolved tokens, never execute Mautic logic in SES. */
final class SharedTemplateCompiler
{
    private array $cache = [];

    public function reset(): void
    {
        $this->cache = [];
    }

    /** @return array{template: array<string, string>, data: string} */
    public function compile(MauticMessage $message, array $tokens): array
    {
        if ($message->getAttachments()) {
            throw new IneligibleMessage('attachments');
        }
        if ($message->getCc() || $message->getBcc()) {
            throw new IneligibleMessage('cc_or_bcc');
        }
        // Explicit MIME bodies (including signed/encrypted content) cannot be reconstructed.
        $body = (new \ReflectionMethod(\Symfony\Component\Mime\Message::class, 'getBody'))->invoke($message);
        if (null !== $body) {
            throw new IneligibleMessage('custom_mime');
        }
        if ('utf-8' !== strtolower($message->getHtmlCharset() ?? 'utf-8') || 'utf-8' !== strtolower($message->getTextCharset() ?? 'utf-8')) {
            throw new IneligibleMessage('charset');
        }
        $source = ['Subject' => $message->getSubject() ?? ''];
        foreach (['Html' => $message->getHtmlBody(), 'Text' => $message->getTextBody()] as $part => $value) {
            if (null !== $value) {
                if (!is_string($value)) {
                    throw new IneligibleMessage('stream_body');
                }
                $source[$part] = $value;
            }
        }
        if (!isset($source['Html']) && !isset($source['Text'])) {
            throw new IneligibleMessage('empty_body');
        }
        ksort($tokens);
        $keys = array_keys($tokens);
        foreach ($tokens as $key => $value) {
            // Non-delimited/overlapping search strings need Mautic's full sequential renderer.
            if (!is_string($key) || !preg_match('/^\{[^{}\r\n]+\}$/D', $key) || (!is_scalar($value) && null !== $value)) {
                throw new IneligibleMessage('unsupported_token');
            }
            $tokens[$key] = (string) $value;
        }
        $lowerKeys = array_map('strtolower', $keys);
        if (count(array_unique($lowerKeys)) !== count($keys)) {
            throw new IneligibleMessage('case_colliding_tokens');
        }
        foreach ($source as $value) {
            if (str_contains($value, '{{') || str_contains($value, '}}')) {
                throw new IneligibleMessage('literal_template_delimiters');
            }
        }
        // Keep the exact sorted, sequential replacement semantics for nested token values.
        $resolved = [];
        $values = array_values($tokens);
        foreach ($keys as $i => $key) {
            $value = str_ireplace(array_slice($keys, $i + 1), array_slice($values, $i + 1), $values[$i]);
            if (str_contains($value, '{{') || str_contains($value, '}}')) {
                throw new IneligibleMessage('literal_template_delimiters');
            }
            $resolved[$key] = $value;
        }
        $cacheKey = hash('sha256', serialize([$source, $keys]));
        if (!isset($this->cache[$cacheKey])) {
            $map = [];
            foreach ($keys as $key) {
                $map[$key] = 'v_'.substr(hash('sha256', $key), 0, 24);
            }
            $template = [];
            $used = [];
            foreach ($source as $part => $value) {
                foreach ($map as $key => $variable) {
                    $value = str_ireplace($key, '{{'.$variable.'}}', $value, $count);
                    if ($count) {
                        $used[$variable] = $key;
                    }
                }
                $template[$part] = $value;
            }
            if (count($this->cache) >= 32) {
                $this->cache = [];
            }
            $this->cache[$cacheKey] = [$template, $used];
        }
        [$template, $used] = $this->cache[$cacheKey];
        $data = [];
        foreach ($used as $variable => $key) {
            $data[$variable] = $resolved[$key];
        }
        // Mautic strips tags from the entire text part iff replacement changed it.
        // Preserve that rule for HTML fragments and tag boundaries spanning tokens.
        if (isset($source['Text'])) {
            $text = str_ireplace($keys, $values, $source['Text']);
            if ($text !== $source['Text'] && str_contains($text, '<')) {
                $template['Text'] = '{{ses_plain_text}}';
                $data['ses_plain_text'] = strip_tags($text);
            }
        }
        try {
            $json = json_encode((object) $data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            json_encode($template, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new IneligibleMessage('invalid_utf8', 0, $e);
        }
        if (strlen($json) > 262144) {
            throw new IneligibleMessage('replacement_data_size');
        }

        return ['template' => $template, 'data' => $json];
    }
}
