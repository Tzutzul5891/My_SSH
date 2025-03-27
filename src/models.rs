use diesel::prelude::*;
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::associations::HasTable;
use diesel::r2d2::{ConnectionManager, PooledConnection};

#[derive(Queryable)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
}

impl User {
    pub fn authenticate(mut conn: PooledConnection<ConnectionManager<MysqlConnection>>, user_name: &str, password: &str) -> Result<User, diesel::result::Error> {
        use crate::schema::users::dsl::*;

        let user = users.filter(username.eq(user_name))
            .first::<User>(&mut conn)?;

        if verify(password, &user.password_hash).unwrap_or(false) {
            Ok(user)
        } else {
            Err(diesel::result::Error::NotFound)
        }
    }
}

pub fn create_user(conn: &mut MysqlConnection, user_name: &str, password: &str) -> Result<User, diesel::result::Error> {
    use crate::schema::users::dsl::*;

    let hashed_password = hash(password, DEFAULT_COST).unwrap();
    let new_user = NewUser {
        username: user_name,
        password_hash: &hashed_password,
    };

    diesel::insert_into(users::table())
        .values(&new_user)
        .execute(conn)?;

    users.filter(username.eq(user_name))
        .first::<User>(conn)
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
}