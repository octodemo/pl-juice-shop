/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      const logsRoot = path.resolve('logs') // Absolute path of logs/
      let filePath
      try {
        filePath = fs.realpathSync(path.resolve(logsRoot, file))
      } catch (e) {
        res.status(404)
        return next(new Error('Log file not found'))
      }
      if (!filePath.startsWith(logsRoot + path.sep)) {
        res.status(403)
        return next(new Error('Access to log files outside logs/ is not allowed!'))
      }
      res.sendFile(filePath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
