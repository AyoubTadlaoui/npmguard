//! Typosquat detection via Levenshtein distance to a baked-in popular-package list.
//!
//! We don't ship a full top-1000; v0.1 uses a curated list of the most-typosquatted
//! npm names (the ones that show up over and over in supply-chain incidents).

use strsim::damerau_levenshtein;

use crate::types::{PackageRef, Signal, SignalKind};

const POPULAR_NAMES: &[&str] = &[
    "react",
    "react-dom",
    "vue",
    "angular",
    "lodash",
    "axios",
    "express",
    "next",
    "tailwindcss",
    "typescript",
    "vite",
    "webpack",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chalk",
    "commander",
    "chokidar",
    "moment",
    "dayjs",
    "uuid",
    "yargs",
    "zod",
    "rxjs",
    "ramda",
    "dotenv",
    "cors",
    "body-parser",
    "socket.io",
    "mongoose",
    "sequelize",
    "prisma",
    "redux",
    "@reduxjs/toolkit",
    "react-router",
    "react-router-dom",
    "react-query",
    "@tanstack/react-query",
    "framer-motion",
    "styled-components",
    "@emotion/react",
    "@emotion/styled",
    "antd",
    "@mui/material",
    "bootstrap",
    "jquery",
    "underscore",
    "request",
    "node-fetch",
    "got",
    "ws",
    "puppeteer",
    "playwright",
    "cheerio",
    "fs-extra",
    "glob",
    "minimatch",
    "rimraf",
    "semver",
    "debug",
    "winston",
    "pino",
    "morgan",
    "helmet",
    "passport",
    "bcrypt",
    "jsonwebtoken",
    "argon2",
    "pg",
    "mysql2",
    "redis",
    "ioredis",
    "@types/node",
    "@types/react",
    "@types/react-dom",
];

pub fn evaluate(pkg: &PackageRef) -> Vec<Signal> {
    let target = pkg.name.to_ascii_lowercase();
    // Don't flag the popular names themselves.
    if POPULAR_NAMES
        .iter()
        .any(|n| n.eq_ignore_ascii_case(&target))
    {
        return Vec::new();
    }
    let mut best: Option<(&str, usize)> = None;
    for candidate in POPULAR_NAMES {
        let d = damerau_levenshtein(&target, candidate);
        if d == 0 {
            continue;
        }
        if best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((candidate, d));
        }
    }
    let Some((candidate, distance)) = best else {
        return Vec::new();
    };
    // Heuristic: a single Damerau-Levenshtein edit (substitution, insert,
    // delete, or adjacent swap) away from a popular name, on names long
    // enough that random collision is unlikely.
    if distance == 1 && candidate.len() > 4 {
        return vec![Signal {
            kind: SignalKind::Typosquat,
            points: 25,
            detail: format!(
                "name '{}' is 1 edit away from popular package '{}'",
                pkg.name, candidate
            ),
        }];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lodahs_flags_as_typosquat_of_lodash() {
        let sigs = evaluate(&PackageRef::new("lodahs", None));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::Typosquat);
    }

    #[test]
    fn react_itself_is_not_flagged() {
        let sigs = evaluate(&PackageRef::new("react", None));
        assert!(sigs.is_empty());
    }

    #[test]
    fn unrelated_name_is_not_flagged() {
        let sigs = evaluate(&PackageRef::new("zustand", None));
        assert!(sigs.is_empty());
    }
}
