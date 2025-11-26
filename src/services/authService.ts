import { supabase } from '@/lib/supabaseClient'
import bcrypt from 'bcryptjs'

/**
 * AuthService - Authenticates admin users using the custom admin_users table
 * with bcrypt password hashing. Maintains a local fallback session in localStorage
 * for synchronous checks.
 */

const LOCAL_SESSION_KEY = 'admin_local_session_v1'

export class AuthService {
  async initializeAdminUser(email: string, _password: string): Promise<void> {
    return
  }

  async signInAdmin(email: string, password: string) {
    try {
      const { data, error } = await supabase
        .from('admin_users')
        .select('id, email, password_hash')
        .eq('email', email)
        .maybeSingle()

      if (error) {
        console.error('Error fetching admin user:', error)
        throw new Error('Invalid login credentials')
      }

      if (!data) {
        throw new Error('Invalid login credentials')
      }

      const isPasswordValid = await bcrypt.compare(password, data.password_hash)
      if (!isPasswordValid) {
        throw new Error('Invalid login credentials')
      }

      this.setLocalAdminSession(email)
      return { user: { id: data.id, email: data.email } }
    } catch (err) {
      if (err instanceof Error) {
        throw err
      }
      throw new Error('Authentication failed')
    }
  }

  async signOut() {
    this.clearLocalAdminSession()
  }

  setLocalAdminSession(email: string) {
    try {
      localStorage.setItem(LOCAL_SESSION_KEY, JSON.stringify({ email, ts: Date.now() }))
    } catch {
      // ignore
    }
  }

  clearLocalAdminSession() {
    try {
      localStorage.removeItem(LOCAL_SESSION_KEY)
    } catch {
      // ignore
    }
  }

  getLocalAdminSession(): { email: string; ts: number } | null {
    try {
      const raw = localStorage.getItem(LOCAL_SESSION_KEY)
      if (!raw) return null
      return JSON.parse(raw)
    } catch {
      return null
    }
  }

  isAuthenticated(): boolean {
    return this.getLocalAdminSession() !== null
  }

  async syncAuth(): Promise<boolean> {
    try {
      const session = this.getLocalAdminSession()
      if (!session) {
        return false
      }
      return true
    } catch (err) {
      console.error('Failed to sync auth:', err)
      this.clearLocalAdminSession()
      return false
    }
  }

  onAuthStateChange(callback: (isAuthenticated: boolean) => void) {
    const isAuth = this.isAuthenticated()
    callback(isAuth)
    return () => {}
  }
}

export const authService = new AuthService()
