/*
 * HARVEST (High-speed Asynchronous Rust Vocabulary Extraction and Search Tool) is an OSINT tool to recursively
 * crawl through a supplied web page, and gather useful information including a wordlist of less-common words
 * found, a list of email addresses found, a list of social media accounts found, and more.
 *
 * Author: Ember Hext
 * GitHub: https://github.com/EmberHext
 * Twitter: @EmberHext
 *
 * It is released under the MIT License:
 *
 * Copyright 2023 Ember Hext
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the “Software”), to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 * Note: This is intended to be used for your own servers or in contexts like pentesting and CTFs where you are authorised
 * to be engaging with the server in this manner.
 *
 */

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
    str::FromStr,
};

use select::{
    document::Document,
    node::Node,
    predicate::{Attr, Name, Predicate},
};

use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT},
    Url,
};

use clap::Parser;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

struct Or(Vec<Box<dyn Predicate>>);

impl Predicate for Or {
    fn matches(&self, node: &Node) -> bool {
        self.0.iter().any(|predicate| predicate.matches(node))
    }
}

struct CrawlConfig {
    max_depth: u32,
    common_words_limit: usize,
    follow_offsite: bool,
    min_length: usize,
    user_agent: Option<String>,
    headers: HeaderMap,
}

fn headers_from_strings(headers: &[String]) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut header_map = HeaderMap::new();
    for header in headers {
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() == 2 {
            let name = parts[0].trim();
            let value = parts[1].trim();
            let header_name = HeaderName::from_str(name)?;
            let header_value = HeaderValue::from_str(value)?;
            header_map.insert(header_name, header_value);
        } else {
            return Err(format!("Invalid header format: {}", header).into());
        }
    }
    Ok(header_map)
}

fn process_node(
    node: &Node,
    base_url: &Url,
    depth: u32,
    word_count: &mut HashMap<String, u32>,
    visited_urls: &mut HashSet<Url>,
    config: &CrawlConfig,
) {
    if depth <= config.max_depth {
        let link = node.attr("href").and_then(|href| base_url.join(href).ok());

        if let Some(url) = link {
            // Only follow the link if follow_offsite is true or if the domains match
            if config.follow_offsite || url.domain() == base_url.domain() {
                if let Ok(new_word_count) =
                    unique_words_from_url_recursive(&url, depth + 1, visited_urls, config)
                {
                    for (word, count) in new_word_count {
                        *word_count.entry(word).or_insert(0) += count;
                    }
                }
            }
        }
    }
}

fn unique_words_from_url_recursive(
    url: &Url,
    depth: u32,
    visited_urls: &mut HashSet<Url>,
    config: &CrawlConfig,
) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    if !visited_urls.insert(url.clone()) {
        // If the URL is already in the visited set, return an empty HashMap
        return Ok(HashMap::new());
    }
    let mut req_headers = HeaderMap::new();
    if let Some(ref agent) = config.user_agent {
        req_headers.insert(USER_AGENT, HeaderValue::from_str(agent)?);
    }

    let client = reqwest::blocking::Client::builder()
        .default_headers(config.headers.clone())
        .build()?;

    let resp = client.get(url.as_str()).send()?;

    let document = Document::from_read(resp)?;

    let tags = vec![
        Name("h1"),
        Name("h2"),
        Name("h3"),
        Name("h4"),
        Name("h5"),
        Name("h6"),
        Name("p"),
        Name("li"),
        Name("dt"),
        Name("dd"),
        Name("blockquote"),
        Name("q"),
        Name("cite"),
        Name("caption"),
        Name("th"),
        Name("td"),
        Name("pre"),
        Name("code"),
        Name("strong"),
        Name("em"),
        Name("mark"),
        Name("small"),
        Name("del"),
        Name("ins"),
        Name("sub"),
        Name("sup"),
        Name("a"),
    ];

    let or_predicate = Or(tags
        .into_iter()
        .map(|tag| Box::new(tag) as Box<dyn Predicate>)
        .collect());
    let elements = document.find(or_predicate);

    let mut word_count = HashMap::new();
    let link_predicate = Attr("href", ());

    let common_words_file = File::open(Path::new("src/resources/commonwords.txt"))?;
    let common_words_reader = BufReader::new(common_words_file);
    let common_words: HashSet<_> = common_words_reader
        .lines()
        .take(config.common_words_limit)
        .filter_map(Result::ok)
        .collect();

    let re = Regex::new(r"[^a-zA-Z']+").unwrap();

    for node in elements {
        let text = node.text();
        let text = text.nfc().collect::<String>();

        for word in text.split_whitespace() {
            let cleaned_word: String = word.to_lowercase();
            // Check if the cleaned_word contains any special characters and if it meets the minimum length requirement
            if !re.is_match(&cleaned_word)
                && !cleaned_word.is_empty()
                && !common_words.contains(&cleaned_word)
                && cleaned_word.len() >= config.min_length
            {
                *word_count.entry(cleaned_word).or_insert(0) += 1;
            }
        }

        if depth <= config.max_depth {
            for link_node in node.find(link_predicate.clone()) {
                process_node(
                    &link_node,
                    url,
                    depth,
                    &mut word_count,
                    visited_urls,
                    config,
                );
            }
        }
    }

    Ok(word_count)
}

fn unique_words_from_url(
    url: &str,
    config: &CrawlConfig,
) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    let parsed_url = Url::parse(url)?;
    let mut visited_urls = HashSet::new();
    unique_words_from_url_recursive(&parsed_url, 0, &mut visited_urls, config)
}

#[derive(Parser, Debug)]
#[command(name = "harvest")]
#[command(author = "Ember Hext <github.com/EmberHext")]
#[command(version = "1.0")]
#[command(
    about = "Crawl through a website for interesting words and more",
    long_about = "Crawl through a website for interesting words, email addresses, and social media links"
)]
struct Cli {
    /// Link to page to search
    url: String,
    /// File to output wordlist into
    #[arg(short, long = "file", value_name = "FILE")]
    wlfile: Option<String>,
    /// Do not output a wordlist
    #[arg(short, long)]
    nowords: bool,
    /// Find all emails
    #[arg(short, long)]
    email: bool,
    /// File to output emails into
    #[arg(long, value_name = "FILE")]
    emfile: Option<String>,
    /// Find all socials
    #[arg(short, long)]
    social: bool,
    /// File to output socials into
    #[arg(long, value_name = "FILE")]
    socfile: Option<String>,
    /// Depth to crawl, default is 2
    #[arg(short, long, value_name = "x")]
    depth: Option<u8>,
    /// Minimum word length, default is 4
    #[arg(short, long, value_name = "x")]
    min: Option<u8>,
    /// The number of most common words to filter, default is 400, max is 1000
    #[arg(short, long, value_name = "x")]
    common: Option<u8>,
    /// Allow the crawler to follow external links
    #[arg(short, long)]
    offsite: bool,
    /// User agent to send in http header
    #[arg(short, long, value_name = "AGENT")]
    agent: Option<String>,
    /// Coverty all words to lowercase
    #[arg(short, long)]
    lower: bool,
    /// Parses words that contains diacritics, but removes the diacritics
    #[arg(short = 'r', long)]
    diacrit_remove: bool,
}

fn main() {
    let url = "https://nytimes.com";
    let max_depth = 3;
    let common_words_limit = 1000;
    let output_file_path = "output.txt";
    let follow_offsite = false;
    let min_length = 5;
    let min_count = 4;
    let user_agent: Option<String> = Some("Edg/112.0.1722.34".to_string());
    let headers =
        headers_from_strings(&["Accept-Charset: iso-8859-5, Unicode-1-1; q = 0,8".to_string()])
            .unwrap_or_else(|err| {
                eprintln!("Error: {}", err);
                std::process::exit(1);
            });

    let config = CrawlConfig {
        max_depth,
        common_words_limit,
        follow_offsite,
        min_length,
        user_agent,
        headers,
    };

    match unique_words_from_url(url, &config) {
        Ok(word_count) => {
            let mut file = File::create(output_file_path).expect("Unable to create file");

            let mut sorted_word_count: Vec<(&String, &u32)> = word_count.iter().collect();
            sorted_word_count.sort_by(|a, b| b.1.cmp(a.1));

            sorted_word_count = sorted_word_count
                .into_iter()
                .filter(|(_, &count)| count >= min_count)
                .collect();

            for (word, count) in sorted_word_count {
                writeln!(file, "{}: {}", word, count).expect("Unable to write data");
            }

            println!("Results have been written to '{}'", output_file_path);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
