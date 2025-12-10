/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

// Ensure URL is available (global in Node >=10, but explicit import for clarity)
import { URL } from 'url'

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      challengeUtils.solveIf(challenges.csrfChallenge, () => {
        const allowedHost = 'htmledit.squarefree.com'
        const originHeader = req.headers.origin
        const refererHeader = req.headers.referer
        let isValidOrigin = false
        try {
          if (originHeader) {
            const originUrl = new URL(originHeader)
            isValidOrigin = originUrl.hostname === allowedHost
          }
        } catch (e) {}
        try {
          if (!isValidOrigin && refererHeader) {
            const refererUrl = new URL(refererHeader)
            isValidOrigin = refererUrl.hostname === allowedHost
          }
        } catch (e) {}
        return isValidOrigin && req.body.username !== user.username
      })

      const savedUser = await user.update({ username: req.body.username })
      const userWithStatus = utils.queryResultToJson(savedUser)
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)
      res.cookie('token', updatedToken)
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      next(error)
    }
  }
}
