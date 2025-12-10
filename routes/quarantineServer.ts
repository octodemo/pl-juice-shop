/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      const quarantineRoot = path.resolve('ftp/quarantine/')
      const requestedPath = path.resolve(quarantineRoot, file)
      if (requestedPath.startsWith(quarantineRoot + path.sep)) {
        res.sendFile(requestedPath)
      } else {
        res.status(403)
        next(new Error('Attempt to access file outside of quarantine!'))
      }
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
